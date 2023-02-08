# MicroShop authentication service

Microservice with authentication logic for my MicroShop project

## Contributing

Guide how to install and run this project on your local machine

> First of all, you need to init `.env` file in base project directory using example in `.env.example`

### Running in Docker

If you already have [`pdm`](https://pdm.fming.dev/latest/), `docker` and `docker-compose-plugin`,
you can just run pdm command:

```
pdm run docker-dev
```

Or, if you don't have `pdm`, you can just run `docker compose`:

```
docker compose -f docker-compose-dev.yml up --build
```
### Running without Docker

If you don't have [`pdm`](https://pdm.fming.dev/latest/), install it and run the following commands:

```
pdm install
pdm run dev
```

## API Documentation

You can see swagger docs on `/docs` and ReDoc on `/redoc` urls in local project (**not available in production**)

## Authors

- Artyom Loskan - [artemowkin](https://github.com/artemowkin)

## License

[MIT](https://opensource.org/licenses/MIT)