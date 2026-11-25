use crate::types::{ByteBudget, ByteLease};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

struct LeasedBytes {
    bytes: Bytes,
    _lease: ByteLease,
}

impl AsRef<[u8]> for LeasedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn lease_bytes(bytes: Bytes, lease: ByteLease) -> Bytes {
    Bytes::from_owner(LeasedBytes {
        bytes,
        _lease: lease,
    })
}

pub(crate) struct LeasedBuffer {
    bytes: Vec<u8>,
    lease: ByteLease,
}

impl LeasedBuffer {
    pub(crate) fn new(lease: ByteLease) -> Self {
        Self {
            bytes: Vec::new(),
            lease,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn try_extend(&mut self, bytes: &[u8]) -> io::Result<bool> {
        let needed = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("response buffer size overflow"))?;
        if !self.lease.grow(needed.saturating_sub(self.lease.bytes())) {
            return Ok(false);
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(io::Error::other)?;
        if !self
            .lease
            .grow(self.bytes.capacity().saturating_sub(self.lease.bytes()))
        {
            return Ok(false);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(true)
    }

    pub(crate) fn replace_lease(&mut self, lease: ByteLease) {
        assert!(lease.bytes() >= self.bytes.capacity());
        self.lease = lease;
    }

    pub(crate) fn discard_prefix(&mut self, bytes: usize) {
        self.bytes.drain(..bytes);
        if self.bytes.is_empty() {
            self.bytes = Vec::new();
            drop(self.lease.split(self.lease.bytes()));
        }
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        lease_bytes(Bytes::from(self.bytes), self.lease)
    }

    pub(crate) fn into_text(self) -> Result<(String, ByteLease), std::string::FromUtf8Error> {
        String::from_utf8(self.bytes).map(|text| (text, self.lease))
    }
}

impl io::Write for LeasedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.try_extend(bytes)? {
            Ok(bytes.len())
        } else {
            Err(io::Error::other("proxy byte budget exhausted"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct ProxyBody<B> {
    inner: B,
    budget: Arc<ByteBudget>,
    done: bool,
}

impl<B> ProxyBody<B> {
    pub(crate) fn new(inner: B, budget: Arc<ByteBudget>) -> Self {
        Self {
            inner,
            budget,
            done: false,
        }
    }
}

impl<B> Body for ProxyBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let frame = match frame.into_data() {
                    Ok(bytes) => {
                        let Some(lease) = this.budget.try_acquire(bytes.len()) else {
                            this.done = true;
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "proxy byte budget exhausted",
                            ))));
                        };
                        Frame::data(lease_bytes(bytes, lease))
                    }
                    Err(frame) => frame,
                };
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.done = true;
                Poll::Ready(Some(Err(io::Error::other(err.to_string()))))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }
}

pub(crate) trait StreamValidator: Send + Sync + Unpin {
    fn validate_chunk(&mut self, chunk: &[u8]) -> io::Result<()>;
    fn validate_eof(&mut self) -> io::Result<()>;
    fn on_too_large(&mut self) {}
    fn on_timeout(&mut self) {}
    fn on_read_error(&mut self, _err: &io::Error) {}
}

pub(crate) struct PrefixedBody<B> {
    prefix: Option<Bytes>,
    rest: B,
    validator: Option<Box<dyn StreamValidator>>,
    total_bytes: usize,
    max_bytes: usize,
    frame_timeout: Duration,
    frame_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    done: bool,
}

impl<B> PrefixedBody<B> {
    pub(crate) fn new(
        prefix: Bytes,
        rest: B,
        validator: Box<dyn StreamValidator>,
        max_bytes: usize,
        frame_timeout: Duration,
    ) -> Self {
        let total_bytes = prefix.len();
        Self {
            prefix: (!prefix.is_empty()).then_some(prefix),
            rest,
            validator: Some(validator),
            total_bytes,
            max_bytes,
            frame_timeout,
            frame_sleep: None,
            done: false,
        }
    }
}

impl<B> Body for PrefixedBody<B>
where
    B: Body<Data = Bytes, Error = io::Error> + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(prefix) = this.prefix.take() {
            if this.total_bytes > this.max_bytes {
                if let Some(mut validator) = this.validator.take() {
                    validator.on_too_large();
                }
                this.done = true;
                return Poll::Ready(Some(Err(io::Error::other(
                    "request body exceeds maximum size",
                ))));
            }
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        match Pin::new(&mut this.rest).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.frame_sleep = None;
                if let Some(chunk) = frame.data_ref()
                    && !chunk.is_empty()
                {
                    match this.total_bytes.checked_add(chunk.len()) {
                        Some(next) if next <= this.max_bytes => {
                            this.total_bytes = next;
                        }
                        _ => {
                            if let Some(mut validator) = this.validator.take() {
                                validator.on_too_large();
                            }
                            this.done = true;
                            return Poll::Ready(Some(Err(io::Error::other(
                                "request body exceeds maximum size",
                            ))));
                        }
                    }
                    if let Some(validator) = this.validator.as_mut()
                        && let Err(err) = validator.validate_chunk(chunk)
                    {
                        this.validator = None;
                        this.done = true;
                        return Poll::Ready(Some(Err(err)));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.frame_sleep = None;
                if let Some(mut validator) = this.validator.take() {
                    validator.on_read_error(&err);
                }
                this.done = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                this.frame_sleep = None;
                this.done = true;
                if let Some(mut validator) = this.validator.take()
                    && let Err(err) = validator.validate_eof()
                {
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(None)
            }
            Poll::Pending => {
                let sleep = this
                    .frame_sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.frame_timeout)));
                if sleep.as_mut().poll(cx).is_ready() {
                    this.frame_sleep = None;
                    if let Some(mut validator) = this.validator.take() {
                        validator.on_timeout();
                    }
                    this.done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body frame read timed out",
                    ))));
                }
                Poll::Pending
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        if self.validator.is_some() {
            return SizeHint::default();
        }
        let rest_hint = self.rest.size_hint();
        let prefix_len = self.prefix.as_ref().map_or(0, |b| b.len() as u64);
        let mut out = SizeHint::new();
        out.set_lower(rest_hint.lower().saturating_add(prefix_len));
        if let Some(upper) = rest_hint.upper().and_then(|u| u.checked_add(prefix_len)) {
            out.set_upper(upper);
        }
        out
    }

    fn is_end_stream(&self) -> bool {
        self.done
            || (self.prefix.is_none() && self.validator.is_none() && self.rest.is_end_stream())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn proxy_frames_hold_budget_until_all_bytes_are_consumed() {
        let budget = ByteBudget::new(8);
        let mut body = ProxyBody::new(Full::new(Bytes::from_static(b"payload")), budget.clone());
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let retained = bytes.slice(2..);
        drop(bytes);
        drop(body);
        assert_eq!(budget.used(), 7);

        let mut next = ProxyBody::new(Full::new(Bytes::from_static(b"next")), budget.clone());
        assert!(next.frame().await.unwrap().is_err());
        assert!(next.frame().await.is_none());
        assert_eq!(budget.used(), 7);

        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    struct RejectOnMarker {
        saw_ok: bool,
        allow_eof: bool,
    }

    impl StreamValidator for RejectOnMarker {
        fn validate_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
            if chunk.contains(&b'!') {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk"));
            }
            self.saw_ok = true;
            Ok(())
        }

        fn validate_eof(&mut self) -> io::Result<()> {
            if self.allow_eof && self.saw_ok {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "truncated eof"))
            }
        }
    }

    #[tokio::test]
    async fn prefixed_body_validator_aborts_before_bad_frame_and_checks_eof() {
        let budget = ByteBudget::new(1024);
        let rest = ProxyBody::new(Full::new(Bytes::from_static(b"bad!chunk")), budget.clone());
        let mut body = PrefixedBody::new(
            Bytes::from_static(b"prefix:"),
            rest,
            Box::new(RejectOnMarker {
                saw_ok: false,
                allow_eof: true,
            }),
            1024,
            Duration::from_secs(5),
        );
        let f0 = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&f0[..], b"prefix:");
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.is_none());

        let rest_eof = ProxyBody::new(Full::new(Bytes::from_static(b"clean")), budget.clone());
        let mut body_eof = PrefixedBody::new(
            Bytes::from_static(b"prefix:"),
            rest_eof,
            Box::new(RejectOnMarker {
                saw_ok: false,
                allow_eof: false,
            }),
            1024,
            Duration::from_secs(5),
        );
        assert!(body_eof.frame().await.unwrap().is_ok());
        assert!(body_eof.frame().await.unwrap().is_ok());
        assert!(body_eof.frame().await.unwrap().is_err());
        assert!(body_eof.frame().await.is_none());

        let saw_too_large = Arc::new(std::sync::atomic::AtomicBool::new(false));
        struct FlagValidator {
            too_large: Arc<std::sync::atomic::AtomicBool>,
        }
        impl StreamValidator for FlagValidator {
            fn validate_chunk(&mut self, _chunk: &[u8]) -> io::Result<()> {
                Ok(())
            }
            fn validate_eof(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn on_too_large(&mut self) {
                self.too_large
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let rest_big = ProxyBody::new(Full::new(Bytes::from_static(b"12345")), budget);
        let mut body_big = PrefixedBody::new(
            Bytes::from_static(b"prefix:"),
            rest_big,
            Box::new(FlagValidator {
                too_large: Arc::clone(&saw_too_large),
            }),
            10,
            Duration::from_secs(5),
        );
        assert!(body_big.frame().await.unwrap().is_ok());
        assert!(body_big.frame().await.unwrap().is_err());
        assert!(saw_too_large.load(std::sync::atomic::Ordering::SeqCst));
    }
}
