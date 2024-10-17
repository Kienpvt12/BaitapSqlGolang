package gin

import (
	"fmt"
	"net/http"

	// "strings"
	"todo-app/domain"
	"todo-app/pkg/clients"
	"todo-app/pkg/tokenprovider"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserService interface {
	Register(data *domain.UserCreate) error
	Login(data *domain.UserLogin) (tokenprovider.Token, error)
	GetAllUser() ([]domain.User, error)
	GetUserByID(id uuid.UUID) (domain.User, error)
	UpdateUser(id uuid.UUID, user *domain.UserUpdate) error
	DeleteUser(id uuid.UUID) error
}

type userHandler struct {
	userService UserService
	// tokenProvider tokenprovider.TokenProvider
}

func NewUserHandler(apiVersion *gin.RouterGroup, svc UserService, authMiddleware gin.HandlerFunc, rateLimitMiddleware gin.HandlerFunc) {
	userHandler := &userHandler{
		userService: svc,
	}

	users := apiVersion.Group("/users")
	// users.Use(authMiddleware)  // Thay đổi middlewareAuth thành authMiddleware
	users.POST("/register", userHandler.RegisterUserHandler)
	users.POST("/login", userHandler.LoginHandler)
	users.GET("", authMiddleware, userHandler.GetAllUserHandler)
	users.GET("/:id", authMiddleware, userHandler.GetUserHandler)
	users.PATCH("/:id", authMiddleware, userHandler.UpdateUserHandler)
	users.DELETE("/:id", authMiddleware, userHandler.DeleteUserHandler)
}

// RegisterUserHandler handles the creation of a new users.
//
// @Summary      Create a new users
// @Description  This endpoint allows authenticated users to create an item.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        users body      domain.UserCreate	  true  "Users creation payload"
// @Success      200   {object}  clients.SuccessRes   "Users successfully created"
// @Failure      400   {object}  clients.AppError     "Bad Request"
// @Failure      401   {object}  clients.AppError     "Unauthorized"
// @Failure      500   {object}  clients.AppError     "Internal Server Error"
// @Router       /users/register [post]
func (h *userHandler) RegisterUserHandler(c *gin.Context) {
	var data domain.UserCreate

	if err := c.ShouldBind(&data); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	if err := h.userService.Register(&data); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(data.ID))
}

// LoginHandler handles the login of a new users.
//
// @Summary      Login users
// @Description  This endpoint allows authenticated users to create an item.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        users body      domain.UserLogin	  true  "Users creation payload"
// @Success      200   {object}  clients.SuccessRes   "Users successfully created"
// @Failure      400   {object}  clients.AppError     "Bad Request"
// @Failure      401   {object}  clients.AppError     "Unauthorized"
// @Failure      500   {object}  clients.AppError     "Internal Server Error"
// @Router       /users/login [post]
func (h *userHandler) LoginHandler(c *gin.Context) {
	var data domain.UserLogin

	if err := c.ShouldBind(&data); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	token, err := h.userService.Login(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(token))
}

// GetAllUserHandler retrieves all users.
//
// @Summary      Get all user
// @Description  This endpoint retrieves a list of all users.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Success      200  {object}  clients.SuccessRes  "List of user retrieved successfully"
// @Failure      500  {object}  clients.AppError    "Internal Server Error"
// @Router       /users [get]
func (h *userHandler) GetAllUserHandler(c *gin.Context) {
	users, err := h.userService.GetAllUser()
	if err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(users))
}

// GetUserHandler retrieves user
// @Summary		 Get an users by ID
// @Description
// @Tags         Users
// Accept 		 json
// Produce 		 json
// @Param        id   path      string                 true  "Users ID"
// @Success      200  {object}  clients.SuccessRes     "Users retrieved successfully"
// @Failure      400  {object}  clients.AppError       "Invalid ID format or bad request"
// @Failure      404  {object}  clients.AppError       "Users not found"
// @Failure      500  {object}  clients.AppError       "Internal Server Error"
// @Router       /users/{id} [get]
func (h *userHandler) GetUserHandler(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	user, err := h.userService.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(user))
}

// UpdateUserHandler updates an existing users.
//
// @Summary      Update an users
// @Description  This endpoint allows updating the properties of an existing item by its ID.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Users ID"
// @Param        users body      domain.UserUpdate      true  "Users update payload"
// @Success      200   {object}  clients.SuccessRes     "Users updated successfully"
// @Failure      400   {object}  clients.AppError       "Invalid input or bad request"
// @Failure      404   {object}  clients.AppError       "Users not found"
// @Failure      500   {object}  clients.AppError       "Internal Server Error"
// @Router       /users/{id} [put]
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (h *userHandler) UpdateUserHandler(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, clients.ErrInvalidRequest(err))
		return
	}

	user := domain.UserUpdate{}
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	fmt.Println("Received data:", user)

	if user.Password != "" {
		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal Server Error",
			})
			return
		}
		user.Password = hashedPassword
	}

	if err := h.userService.UpdateUser(id, &user); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(true))
}

// DeleteUserHandler deletes an Users by its ID.
//
// @Summary      Delete an users
// @Description  This endpoint deletes an item identified by its unique ID.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        id   path      string                 true  "Users ID"
// @Success      200  {object}  clients.SuccessRes     "Users deleted successfully"
// @Failure      400  {object}  clients.AppError       "Invalid ID format or bad request"
// @Failure      404  {object}  clients.AppError       "Users not found"
// @Failure      500  {object}  clients.AppError       "Internal Server Error"
// @Router       /users/{id} [delete]
func (h *userHandler) DeleteUserHandler(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))
		return
	}

	if err := h.userService.DeleteUser(id); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(true))
}
