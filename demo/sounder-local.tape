Output demo/sounder-local.gif
Set Width 1100
Set Height 720
Set FontSize 22
Set Theme "Dracula"

Type "target/debug/sounder inspect target/s3-fixtures/healthy.parquet"
Enter
Sleep 2s
Type "clear"
Enter

Type "target/debug/sounder check target/s3-fixtures --agent --format markdown"
Enter
Sleep 3s
