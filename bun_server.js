import handle from './handler.js'

Bun.serve({
    port: 3000,
    fetch(request) {
        return handle(request)

    }
})
