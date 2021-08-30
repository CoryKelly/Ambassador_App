package routes

import (
	"ambassador/src/controllers"
	"ambassador/src/middlewares"
	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {

	basePath := app.Group("/")

	// Publish routes
	basePath.Post("register", controllers.Register)
	basePath.Post("login", controllers.Login)

	// Middleware
	userAuthenticated := basePath.Use(middlewares.IsAuthenticated)

	// Private routes
	userAuthenticated.Get("user", controllers.User)
	userAuthenticated.Put("user/info", controllers.UpdateInfo)
	userAuthenticated.Put("user/password", controllers.UpdatePassword)
	userAuthenticated.Post("logout", controllers.Logout)
}
