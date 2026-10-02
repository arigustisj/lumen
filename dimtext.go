package lumen

// DimText membuat teks redup memakai gaya yang terdeteksi.
//
// Berbeda dengan DetectStyle yang menerima io.Writer, pemakai di cmd sering
// hanya perlu satu potongan teks redup tanpa membuat objek Style.
func DimText(s string) string { return DetectStyle(nil).Dim(s) }
