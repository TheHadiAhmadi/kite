import http from 'http'
import handler from '../handler.js'

function getRawBody(req) {
    if(!req.headers['content-type']) {
        return null;
    }
    const length = Number(req.headers['content-length'])

	return new ReadableStream({
		start(controller) {
			req.on('error', (error) => {
				controller.error(error);
			});

			let size = 0;

			req.on('data', (chunk) => {
				size += chunk.length;

				if (size > length) {
					controller.error(new Error('content-length exceeded'));
				}

				controller.enqueue(chunk);
			});

			req.on('end', () => {
				controller.close();
			});
		}
	});
}


// Copied from somewhere else
export async function setResponse(res, response) {
	const headers = Object.fromEntries(response.headers);

	res.writeHead(response.status, headers);

	if (response.body) {
		let cancelled = false;

		const reader = response.body.getReader();

		res.on('close', () => {
			reader.cancel();
			cancelled = true;
		});

		const next = async () => {
			const { done, value } = await reader.read();

			if (cancelled) return;

			if (done) {
				res.end();
				return;
			}

			res.write(Buffer.from(value), (error) => {
				if (error) {
					console.error('Error writing stream', error);
					res.end();
				} else {
					next();
				}
			});
		};

		next();
	} else {
		res.end();
	}
}

function getRequest(req) {
//
    //
    const init = {
        method: req.method,
        url: "http://" + req.headers.host + req.url,
        headers: req.headers,
        body: getRawBody(req)
    }

    return new Request(init.url, init)
}

http.createServer(async (req, res) => {
    const request = getRequest(req)

    const response = await handler(request)

    setResponse(res, response)
}).listen(3000)
