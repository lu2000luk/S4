# S4 API Docs

The S4 API tries to give its tools in as many ways as possible, that could be passing the auth token in headers, query parameters or cookies. In the docs I'll try to show every accepted way to use the api. Passing data truh the body will always be in JSON format.

## User key endpoints
An user key is a simple API key with the same permissions as the user. (ID Format: user_[user id])

### GET /api/user_key
Returns the key as text/plain (With code 200). Pass the password and user_id as query parameters. Example:
```sh
curl -X GET "https://.../api/user_key?user_id=123&password=your_password"
```

### POST /api/user_key
Returns the key as text/plain. Pass the password and user_id as JSON in the body. Example:
```sh
curl -X POST "https://.../api/user_key" -H "Content-Type: application/json" -d '{"user_id":123,"password":"your_password"}'
```

### DELETE /api/user_key
Deletes the user key. Pass the user_id and password in query parameters or body (as JSON). Example:
```sh
curl -X DELETE "https://.../api/user_key?user_id=123&password=your_password"
```
or
```sh
curl -X DELETE "https://.../api/user_key" -H "Content-Type: application/json" -d '{"user_id":123,"password":"your_password"}'
```

### Error format
In case of an error in user key endpoints, the response will not have a 200 status code and the body's text will ALWAYS start with the word "ERROR" followed by a description of the error.

## Auth check endpoint

### GET /api/check_auth

Checks if the provided auth token is valid. Returns code 200 if valid, 401 if not. Pass the key as a query parameter, header or cookie.

Example with query parameter:
```sh
curl -X GET "https://.../api/check_auth?key=..."
```

Example with header:
```sh
curl -X GET "https://.../api/check_auth" -H "Authorization: ..."
```

Example with cookie:
```sh
curl -X GET "https://.../api/check_auth" --cookie "key=..."
```

### POST /api/check_auth

Checks if the provided auth token is valid. Returns code 200 if valid, 401 if not. Pass the key as JSON in the body.

```sh
curl -X POST "https://.../api/check_auth" -H "Content-Type: application/json" -d '{"key":"..."}'
```
