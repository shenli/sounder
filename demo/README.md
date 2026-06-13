# Demo

The VHS source for the public demo is `demo/sounder-local.tape`.

It uses local fixtures only, so it can be rendered without AWS credentials.

Prepare local fixtures before recording:

```bash
cargo run --quiet --example make_s3_fixtures -- target/s3-fixtures
```

Record the local GIF when `vhs` is installed:

```bash
cargo build
VHS_NO_SANDBOX=1 vhs demo/sounder-local.tape
```
