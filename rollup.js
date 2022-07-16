
const kitePlugin = (config) => {
	return {
		name: 'kite',
		async buildStart() {
            console.log(this.getWatchFiles())
            // console.log('clean output directory')
            if(!existsSync(config.output)) {
                mkdirSync(config.output);
            }
            

            // console.log('generating Routes');
            let manifestContent = await processRoutes(config.routes);
            manifestContent = manifestContent.replace(/ROUTES/g, path.relative(config.output, config.routes));
            let manifestFile = 'manifest.js';
            writeFileSync(config.output + '/' + manifestFile, manifestContent);
            
            

            // console.log('copying handler');
			const handlerFile = './node_modules/ht-kit/handler.js'
            let content = readFileSync(handlerFile, 'utf-8');
            content = content.replace('MANIFEST', './' + manifestFile);
            writeFileSync(config.output + '/handler-tmp.js', content);
        
        
			// console.log('copying adapter');
            let adapterContent = readFileSync(`./node_modules/ht-kit/adapters/${config.adapter}/server.js`, 'utf-8');
            adapterContent = adapterContent.replace('HANDLER', './handler.js');
            writeFileSync(config.output + '/server.js', adapterContent);
            
            // console.log('generate dev server')
            let devAdapterContent = readFileSync(`./node_modules/ht-kit/adapters/node/server.js`, 'utf-8');
            devAdapterContent = devAdapterContent.replace('HANDLER', './handler.js');
            writeFileSync(config.output + '/dev-server.js', devAdapterContent)
            
        
		},
		buildEnd() {
			// console.log('kite build end');
		},
		transform(code, id) {
			// console.log('kite transform', id);
			return null;
		}
	};
};

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import {globby} from 'globby'

import { processRoutes } from './src/utils/generateRoutes.mjs';
export default async (config) => {

	return {
		input: config.output + '/handler-tmp.js',

		output: {
			format: 'esm',
			file: config.output + '/handler.js'
		},
		plugins: [
			kitePlugin(config),
			{
				name: 'watchAssets',
				async load() {
					const watch = (file) => this.addWatchFile(file);
					const files = await globby(config.routes + '/**/*.html');
					const resolvedFiles = files.map((file) => path.resolve(file));
					resolvedFiles.map(watch);
				}
			}
		],
		watchChange(id) {
			console.log('watch Change', id);
		},
        watch: {
            include: [config.routes + '/**/*{.html,.js}']
        }
	};
};
