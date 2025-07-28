package utils

// strPtrToStr безопасно преобразует *string в string
func StrPtrToStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
