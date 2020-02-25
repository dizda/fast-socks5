/// Easy to destructure bytes buffers by naming each fields:
///
/// # Examples (before)
///
/// ```
/// let mut buf = [0u8; 2];
/// stream.read_exact(&mut buf).await?;
/// let [version, method_len] = buf;
///
/// assert_eq!(version, 0x05);
/// ```
///
/// # Examples (after)
///
/// ```
/// let [version, method_len] = read_exact!(stream, [0u8; 2]);
///
/// assert_eq!(version, 0x05);
/// ```
#[macro_export]
macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        //        $stream
        //            .read_exact(&mut x)
        //            .await
        //            .map_err(|_| io_err("lol"))?;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}
