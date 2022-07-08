function routeToRegex(string) {
	const pattern = `^${string
		.replace(/\//g, '\\/')
		.replace(/\[\w+\]/g, '(.+)')
		.replace('.js', '')
		.replace('index', '')}$`;

	const names = string
		.split('/')
		.map((sp) => {
			if (sp.indexOf('[') >= 0) return sp.substring(sp.indexOf('[') + 1, sp.indexOf(']'));
			return false;
		})
		.filter(Boolean);

	return {
		pattern,
		names
	};
}

let i = 0;
let map = {};
async function processFolder(path, handlers = [], route = '') {
	let files = [];
	for await (let file of Deno.readDir(path)) {
		files.push(file);
	}

	if (files.some((file) => file.name.startsWith('__middleware.js'))) {
		map[++i] = path + '/__middleware.js';
		handlers.push(i);
	}

	await Promise.all(
		files.map(async (file) => {
			if (file.isFile) {
				map[++i] = path + '/' + file.name;

				const { pattern, names } = routeToRegex(route + '/' + file.name);

				routes.push({
					pattern,
					names,
					handlers: [...handlers, i]
				});
			}

			if (file.isDirectory) {
				await processFolder(path + '/' + file.name, handlers, route + '/' + file.name);
			}
		})
	);
}

let routes = [];

const routesFolder = './src/routes';
await processFolder(routesFolder);

const manifest = `
${Object.entries(map)
	.map(([key, val]) => `import * as $${key} from '${val}'`)
	.join('\n')}

export default {
    routes: [${routes
			.map((route) => {
				return (
					`\n        {\n            pattern: ${new RegExp(route.pattern)},\n` +
					`            paramNames: ${JSON.stringify(route.names)},\n` +
					`            handlers: [${route.handlers.map((h) => '$' + h).join(', ')}]\n` +
					`        },`
				);
			})
			.join('')}\n    ]
}

`;

Deno.writeTextFile('manfiest.js', manifest);
