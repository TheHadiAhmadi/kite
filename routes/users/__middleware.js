export async function handle(event, next) {
    console.log(next)
    return next(event)
}