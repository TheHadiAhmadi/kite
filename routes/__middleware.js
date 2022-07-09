// default middleware
export async function handle(event, next) {

    return await next(event)
}
