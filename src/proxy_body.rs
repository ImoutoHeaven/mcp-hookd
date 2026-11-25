use crate::types::{ByteBudget, ByteLease};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
                            return Poll::Ready(Some(Err(io::Error::other(
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
}
