export async function get({request, params}) {

    const {app, table, data} = params;

    return {
        body: {
            message: "get data",
            app,
            table,
            data
        }

    }
}
