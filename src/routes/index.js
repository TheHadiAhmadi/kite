export async function get(request) {
    console.log('get', request.url)
    return {
        body: "Hello World!",
        status: 200,
        headers: {}
    }
}

export async function post(request) {

    throw new Error('this is error message')
    console.log('post', request.url)
    return {
        body: "This is post",
        status: 201,
        headers: {
            'Content-Type': 'application/json'

        }

    }
}
