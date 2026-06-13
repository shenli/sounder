use std::fs::{self, File};
use std::path::Path;
use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;

fn main() {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/s3-fixtures".to_string());
    let output = Path::new(&output);
    fs::create_dir_all(output).expect("create fixture directory");

    write_parquet(
        &output.join("healthy.parquet"),
        Arc::new(Schema::new(vec![
            Field::new("user_id", DataType::Int64, false),
            Field::new("country", DataType::Utf8, true),
        ])),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec![Some("US"), Some("CA"), Some("US")])),
        ],
    );

    write_parquet(
        &output.join("part-000.parquet"),
        Arc::new(Schema::new(vec![Field::new(
            "user_id",
            DataType::Int64,
            false,
        )])),
        vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
    );

    write_parquet(
        &output.join("part-001.parquet"),
        Arc::new(Schema::new(vec![Field::new(
            "user_id",
            DataType::Utf8,
            false,
        )])),
        vec![Arc::new(StringArray::from(vec![Some("1"), Some("2")]))],
    );

    fs::write(output.join("corrupt.parquet"), b"not parquet").expect("write corrupt fixture");
    println!("{}", output.display());
}

fn write_parquet(path: &Path, schema: Arc<Schema>, columns: Vec<Arc<dyn arrow_array::Array>>) {
    let file = File::create(path).expect("create parquet fixture");
    let mut writer = ArrowWriter::try_new(file, schema.clone(), None).expect("create writer");
    let batch = RecordBatch::try_new(schema, columns).expect("create record batch");
    writer.write(&batch).expect("write record batch");
    writer.close().expect("close writer");
}
