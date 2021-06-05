package errors_utils

func PanicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// func PanicOnAPIError(apiErr *APIError) {
// 	if apiErr != nil {
// 		panic(apiErr)
// 	}
// }
