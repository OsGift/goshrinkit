// -----------------------------------------------------------------------------
// internal/utils/response.go
// -----------------------------------------------------------------------------
package utils

import (
	"encoding/json"
	"fmt"
	"log" // Using standard log for now, can be replaced by logrus if imported
	"net/http"
	"os" // For os.Getenv if needed for ENVIRONMENT in ResponseError

	"github.com/gorilla/mux" // For mux.Vars in C.Params
)

// GeneralResponse returns a standard response format
type GeneralResponse struct {
	Success  bool        `json:"success"`
	Data     interface{} `json:"data,omitempty"`
	Message  string      `json:"message,omitempty"`
	Token    string      `json:"token,omitempty"`
	Error    interface{} `json:"error,omitempty"` // Changed from 'error' to 'Error' for common JSON naming
	Metadata interface{} `json:"metadata,omitempty"`
}

// C serves as a place holder for the http request and response
// This struct and its methods are provided as per user's request.
// However, the main handlers in auth.go and shortener.go will use
// the direct Send*Response functions for simpler integration initially.
// A full integration of 'C' would involve wrapping handlers.
type C struct {
	W http.ResponseWriter
	R *http.Request
}

func (c *C) GetAllHeaders() map[string]string {
	headers := make(map[string]string)
	for name, values := range c.R.Header {
		// Join multiple values with a comma
		headers[name] = values[0]
		if len(values) > 1 {
			for _, value := range values[1:] {
				headers[name] += ", " + value
			}
		}
	}
	return headers
}

// H defines a json type format (legacy from common patterns, equivalent to map[string]interface{})
type H map[string]interface{}

// BindJSON decodes http request body to a given object
func (c *C) BindJSON(data interface{}) error {
	err := json.NewDecoder(c.R.Body).Decode(data)
	if err != nil {
		fmt.Println("Error binding JSON:", err) // Using fmt.Println for now
		return err
	}
	return nil
}

// responseJSON returns a http response encoded in application/json format to the response writer
func responseJSON(res http.ResponseWriter, status int, object interface{}) {
	res.Header().Set("Content-Type", "application/json") // Corrected from Content-Resource
	res.WriteHeader(status)
	err := json.NewEncoder(res).Encode(object)

	if err != nil {
		log.Printf("Error encoding JSON response: %v", err) // Using log.Printf for consistency
		return
	}
}

// Params maps routes params to mux and returns the value of the key
func (c *C) Params(key string) string {
	return mux.Vars(c.R)[key]
}

// --- General Response Helper Functions ---

// SendSuccessResponse sends a successful JSON response with data and message.
func SendSuccessResponse(w http.ResponseWriter, data interface{}, message string, status int) {
	response := GeneralResponse{
		Success: true,
		Data:    data,
		Message: message,
	}
	responseJSON(w, status, response)
}

// SendSuccessWithTokenResponse sends a successful JSON response with data, token, and message.
func SendSuccessWithTokenResponse(w http.ResponseWriter, data interface{}, token, message string, status int) {
	response := GeneralResponse{
		Success: true,
		Data:    data,
		Message: message,
		Token:   token,
	}
	responseJSON(w, status, response)
}

// SendErrorResponse sends an error JSON response with a message.
func SendErrorResponse(w http.ResponseWriter, message string, status int) {
	response := GeneralResponse{
		Success: false,
		Message: message,
	}
	responseJSON(w, status, response)
}

// ResponseError is a more detailed error response handler, provided by the user.
// Some external dependencies are commented out to ensure compilation with current go.mod.
func (c *C) ResponseError(success bool, data interface{}, err error, action string) { // Changed 'error' param to 'err'
	// var userError apperror.UserError
	// ok := errors.As(err, &userError) // Changed 'error' to 'err' for consistency with param
	response := GeneralResponse{
		Success: success,
		Data:    data,
		Message: err.Error(), // Changed 'error' to 'err'
	}
	var status int
	// if ok {
	//     status = http.StatusBadRequest
	// } else {
	status = http.StatusInternalServerError
	// response.Message = apperror.ErrorProcessing{Action: action}.Message() // Commented out
	log.Printf("Error during action '%s': %v", action, err) // Using log.Printf instead of logrus.Error

	// capture error with sentry
	// eventId := sentry.CaptureException(err) // Commented out
	// sentry.CaptureEvent(&sentry.Event{ // Commented out
	// 	EventID: *eventId,
	// 	Extra:   bson.M{"message": err.Error(), "auth": "auth"},
	// 	Message: action,
	// 	Level:   sentry.LevelError,
	// 	User: sentry.User{
	// 		// Email:     c.GetUserEmail(),
	// 		// ID:        c.GetBusinessID(),
	// 		Email:     "default",
	// 		ID:        "default",
	// 		IPAddress: "",
	// 		Username:  "",
	// 	},
	// 	Request: &sentry.Request{
	// 		URL:         c.R.URL.Path,
	// 		Method:      c.R.Method,
	// 		Data:        "",
	// 		QueryString: "",
	// 		Cookies:     "",
	// 		Headers:     nil,
	// 		Env:         nil,
	// 	},
	// })
	slackMessage := map[string]string{
		"Action":      action,
		"Error":       err.Error(), // Changed 'error' to 'err'
		"URL":         c.R.URL.Path,
		"Method":      c.R.Method,
		"Environment": os.Getenv("ENVIRONMENT"), // os.Getenv is fine
	}
	// slackNofify.SendSlackError(slackMessage) // Commented out
	log.Printf("Slack Notification (simulated): %v", slackMessage) // Logging instead of sending to slack
	// }
	responseJSON(c.W, status, response)
}

// ResponseErrorWithMessage directly sends an error response with a status code and message.
// This is effectively the same as SendErrorResponse, provided for consistency with user's requested pattern.
func (c *C) ResponseErrorWithMessage(statusCode int, message string) {
	SendErrorResponse(c.W, message, statusCode)
}

// Response200 sends a 200 OK success response with data and message.
// This is effectively the same as SendSuccessResponse(w, data, message, http.StatusOK).
func (c *C) Response200(data interface{}, message string) {
	SendSuccessResponse(c.W, data, message, http.StatusOK)
}

// Response200Meta sends a 200 OK success response with data, metadata, and message.
func (c *C) Response200Meta(data interface{}, metadata interface{}, message string) {
	responseSuccess := GeneralResponse{
		Success:  true,
		Data:     data,
		Metadata: metadata,
		Message:  message,
	}
	responseJSON(c.W, http.StatusOK, responseSuccess)
}

// Response200WithToken sends a 200 OK success response with data, token, and message.
// This is effectively the same as SendSuccessWithTokenResponse(w, data, token, message, http.StatusOK).
func (c *C) Response200WithToken(data interface{}, token, message string) {
	SendSuccessWithTokenResponse(c.W, data, token, message, http.StatusOK)
}

// Response401 returns a json response with 401 Unauthorized status.
// This is effectively the same as SendErrorResponse(w, resp.Message, http.StatusUnauthorized)
// but matches the user's provided signature.
func Response401(res http.ResponseWriter, resp GeneralResponse) {
	responseJSON(res, http.StatusUnauthorized, resp) // Changed to encode the full GeneralResponse
}
