//! go-mail's two line protections, against the real `net/textproto` `DotWriter` output and over a real
//! socket to a scripted server.

use silo_runtime::mail::smtp::{Client, Security, SendError, dot_stuff};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn dot_stuff_matches_the_real_dot_writer() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/smtp/dot_writer.json"
    );
    let records: Vec<serde_json::Value> =
        silo_gocompat::json::unmarshal(&std::fs::read(path).unwrap()).unwrap();
    assert!(records.len() >= 3000);
    for record in records {
        let input = unhex(record["input_hex"].as_str().unwrap());
        assert_eq!(
            dot_stuff(&input),
            unhex(record["wire_hex"].as_str().unwrap()),
            "input {:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

/// Serves `greeting`, answers each command with 250 (354 for DATA), and returns everything received.
async fn scripted_server(listener: TcpListener, greeting: &'static [u8]) -> Vec<u8> {
    let (stream, _) = listener.accept().await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write.write_all(greeting).await.unwrap();
    let mut all = Vec::new();
    let mut in_data = false;
    loop {
        let mut line = Vec::new();
        if read.read_until(b'\n', &mut line).await.unwrap() == 0 {
            return all;
        }
        all.extend_from_slice(&line);
        if in_data {
            if line == b".\r\n" {
                in_data = false;
                write.write_all(b"250 queued\r\n").await.unwrap();
            }
        } else if line.starts_with(b"QUIT") {
            // The client hangs up without reading the reply, so a reply could race its close
            // and turn the next read into a reset.
            return all;
        } else if line.starts_with(b"DATA") {
            in_data = true;
            write.write_all(b"354 go\r\n").await.unwrap();
        } else {
            write.write_all(b"250 ok\r\n").await.unwrap();
        }
    }
}

#[tokio::test]
async fn a_body_cannot_end_data_early_and_an_address_cannot_inject_a_command() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(scripted_server(listener, b"220 hi\r\n"));

    let (mut client, _, _) = Client::connect("127.0.0.1", port, Security::None, "me")
        .await
        .unwrap();
    assert!(matches!(
        client
            .send_envelope("a@b>\r\nRCPT TO:<evil@x", &["c@d"], b"body")
            .await,
        Err(SendError::NotSent(_))
    ));
    assert!(matches!(
        client
            .send_envelope("a@b", &["c@d>\r\nDATA"], b"body")
            .await,
        Err(SendError::NotSent(_))
    ));
    client
        .send_envelope("a@b", &["c@d"], b"line\r\n.\r\nMAIL FROM:<evil>\r\n")
        .await
        .unwrap();
    client.quit().await;
    drop(client);

    let wire = server.await.unwrap();
    assert_eq!(
        String::from_utf8(wire).unwrap(),
        "EHLO me\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n\
         line\r\n..\r\nMAIL FROM:<evil>\r\n.\r\nQUIT\r\n"
    );
}

#[tokio::test]
async fn a_hostile_reply_is_an_error_not_a_panic() {
    for greeting in [
        "22é hi\r\n".as_bytes(),
        "220é\r\n".as_bytes(),
        "é2 x\r\n".as_bytes(),
        b"220",
        b"220x hi\r\n",
        b"\xff\xfe\xfd\xfc\r\n",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let greeting = greeting.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&greeting).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
        });
        assert!(
            Client::connect("127.0.0.1", port, Security::None, "me")
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn an_ehlo_name_with_a_line_break_is_refused_before_dialing() {
    assert!(matches!(
        Client::connect("127.0.0.1", 1, Security::None, "me\r\nQUIT").await,
        Err(SendError::NotSent(message)) if message.contains("CR or LF")
    ));
}
