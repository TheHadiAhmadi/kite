export async function get({request, params}) {
    console.log('get', request.url)
    return {
        body: {
            items: [1, 2, 3],
            url: new URL(request.url).searchParams.get('url') ?? 'empty'
        },
        status: 200,
        headers: {}
    }
}

export async function post(request) {
    console.log('post', request.url)
    const body = await request.json();

    if(!body) 
        throw new Error('body should not be empty')
    return {
        body: "This is post",
        status: 201,
        headers: {
            'Content-Type': 'application/json'
        }
    }
}

export default async function({request, params, getData}) {

    // TODO: find better way to get data
    const data = await getData()
    return `<h1>this is <b>HTML</b>, data from get: ${JSON.stringify(data)}</h1>`
}
