import handle from 'HANDLER'

console.log('Listening on http://localhost:3000')
Bun.serve({
    port: 3000,
    fetch(request) {
        return handle(request)
    }
})
