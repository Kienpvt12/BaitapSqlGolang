package tokenprovider

type TokenProvider interface {
	ValidateToken(token string) (string, error) // Phương thức để xác thực token và trả về userID hoặc một lỗi
}
