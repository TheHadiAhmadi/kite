export async function get({request, params}) {
    const url = new URL(request.url)
    const id = params.id


    return {
        status: 200,
        body: 'info about user: ' + id
    }
}
