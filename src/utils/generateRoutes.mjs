import fs1 from 'fs';
const fs = fs1.promises;

let i = 0

function routeToRegex(string) {
	let isDynamic = false;
	let isRest = false;
	const pattern = `^${string
		.replace(/\//g, '\\/')
		.replace(/\[\.\.\.\w+\]/g, '(.+)')
		.replace(/\[\w+\]/g, '(\\w+)')
		.replace(/.js$/, '')
		.replace(/.html$/, '')
		.replace('index', '')}$`;

	const names = string
		.split('/')
		.map((sp) => {
			if (sp.indexOf('[...') >= 0) {
				isRest = true;
				isDynamic = true;
				return sp.substring(sp.indexOf('[') + 4, sp.indexOf(']'));
			}
			if (sp.indexOf('[') >= 0) {
				isDynamic = true;
				return sp.substring(sp.indexOf('[') + 1, sp.indexOf(']'));
			}
			return false;
		})
		.filter(Boolean);

	return {
		pattern,
		names,
		isDynamic,
		isRest
	};
}

async function isDirectory(file) {
	return (await fs.stat(file)).isDirectory();
}

async function isFile(file) {
	return (await fs.stat(file)).isFile();
}

export async function processFolder({routes, map}, path, handlers = [], route = '') {
	const files = await fs.readdir(path);


	if (files.some((file) => file.startsWith('__middleware.js'))) {
		map[++i] = route + '/__middleware.js';
		handlers.push(i);
	}


	await Promise.all(
		files.map(async (file) => {
			if (await isFile(path + '/' + file)) {
				let onlyView = false;
				if (file.endsWith('.html')) {
					if (!files.includes(file.replace('.html', '.js'))) {
						onlyView = true;
					} else {
						return;
					}
				}

				if (!onlyView) {
					map[++i] = route + '/' + file;
				}

				const { pattern, names, isDynamic, isRest } = routeToRegex(route + '/' + file);

				function loadView(path) {
					const viewFile = path.replace('.js', '.html');
					let content = fs1.readFileSync(viewFile, 'utf-8')
					content = content.replace(/`/g, '\\`').replace(/\$/g, '\\$')
					try {
						return {
							id: path.replace('.js', '.html'),
							content
						};
					} catch (err) {
						return null;
					}
				}

				routes.push({
					pattern,
					names,
					isDynamic,
					isRest,
					view: loadView(path + '/' + file),
					handlers: onlyView ? [] : [...handlers, i]
				});
			}

			if (await isDirectory(path + '/' + file)) {
				await processFolder({routes, map}, path + '/' + file, handlers, route + '/' + file);
			}
		})
	);

}

function generateManifest(routes, map) {

	const manifest = `/* This file is auto generated from 'generateRoutes.js' file */

${Object.entries(map)
	.map(([key, val]) => `import * as $${key} from 'ROUTES${val}'`)
	.join('\n')}

export default {
    routes: [${routes
			.map((route) => {
				return (
					`\n        {\n            pattern: ${new RegExp(route.pattern)},\n` +
					`            paramNames: ${JSON.stringify(route.names)},\n` +
					`            isDynamic: ${route.isDynamic},\n` +
					`            isRest: ${route.isRest},\n` +
					`${route.view ? `            view: '${route.view.id}',\n` : ''}` +
					`            handlers: [${route.handlers.map((h) => '$' + h).join(', ')}]\n` +
					`        },`
				);
			})
			.join('')}\n    ],
	views: {\n${routes
		.map((route) => {
			if (route.view) {
				return `        '${route.view.id}': \`${route.view.content}\`,\n`;
			}
		})
		.join('')}}
}

`;

	return manifest;
}

export async function processRoutes(folder) {
	const routes = []
	const map = {}
	await processFolder({routes, map}, folder)

	return generateManifest(routes, map)
}

// const routesFolder = '/home/hadi/github/ht-kit-example/routes';
// const manifest = await processRoutes(routesFolder);
// console.log(manifest)
