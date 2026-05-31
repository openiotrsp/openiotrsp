module github.com/openiotrsp/openiotrsp

go 1.26.3

require (
	github.com/damonto/euicc-go v0.0.0
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/jackc/pgerrcode v0.0.0-20220416144525-469b46aa5efa
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)

replace github.com/damonto/euicc-go => github.com/openiotrsp/euicc-go v0.0.0-20260531131843-8a5c8e43d00f
