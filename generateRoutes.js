import fs1 from 'fs'
const fs = fs1.promises

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
	//let files = [];
    const files = await fs.readdir(path)
	//for await (let file of Deno.readDir(path)) {
//		files.push(file);
//	}

	if (files.some((file) => file.startsWith('__middleware.js'))) {
		map[++i] = path + '/__middleware.js';
		handlers.push(i);
	}

    async function isDirectory(name) {
        const stat = await fs.stat(path + '/' + name);
        return stat.isDirectory();
    }
    async function isFile(name) {
        const stat = await fs.stat(path + '/' + name);
        return stat.isFile();
    }


	await Promise.all(
		files.map(async (file) => {
			if (await isFile(file)) {
				map[++i] = path + '/' + file;

				const { pattern, names } = routeToRegex(route + '/' + file);

				routes.push({
					pattern,
					names,
					handlers: [...handlers, i]
				});
			}

			if (await isDirectory(file)) {
				await processFolder(path + '/' + file, handlers, route + '/' + file);
			}
		})
	);
}

let routes = [];

const routesFolder = './routes';
await processFolder(routesFolder);

const manifest = `/* This file is auto generated from 'generateRoutes.js' file */

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

fs.writeFile('manfiest.js', manifest);
