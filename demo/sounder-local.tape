Output demo/sounder-local.gif
Set Width 1100
Set Height 720
Set FontSize 22
Set Theme "Dracula"

Type "sounder inspect target/s3-fixtures/healthy.parquet"
Enter
Sleep 5s
Type "clear"
Enter

Type "sounder inspect target/s3-fixtures/healthy.parquet --head 3"
Enter
Sleep 6s
Type "clear"
Enter

Type "sounder check target/s3-fixtures --agent --format markdown"
Enter
Sleep 7s
