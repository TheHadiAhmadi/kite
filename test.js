import { globby } from "globby"
import path from 'path'
const files = await globby('../ht-kit-example/routes' + '/**/*.html')

files.map(file => {
    return path.resolve(file)
}).map(files => {

    console.log(files)
})