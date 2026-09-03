//! A tick a second, from a thread: the notebook is files and sockets, and a second is how stale
//! a listing may be. iced's own timer needs an async runtime the tree does not carry.

use std::time::Duration;

use iced::Subscription;
use iced::futures::channel::mpsc;

use crate::Message;

/// A [`Message::Tick`] every second, for as long as the subscription is held.
pub(crate) fn every_second() -> Subscription<Message> {
    Subscription::run(ticks)
}

fn ticks() -> mpsc::UnboundedReceiver<Message> {
    let (sender, receiver) = mpsc::unbounded();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            // The receiver going is the subscription ending, which ends this thread.
            if sender.unbounded_send(Message::Tick).is_err() {
                break;
            }
        }
    });
    receiver
}
