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
