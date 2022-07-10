export async function get({request}) {
    console.log("handle 404");
    return {
        body: "404"
    }

}