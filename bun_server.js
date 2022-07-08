import handle from './handler.ts'

Bun.serve({
    port: 3000,
    fetch(request) {
        return handle(request)

    }
})
