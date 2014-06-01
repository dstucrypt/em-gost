
/*
 * em-gost is intended to work in browser environment
 * and be packaged with browserify.
 *
 * However emscripten does not export module globals when
 * running in browser.
 *
 * Contents of this file are added after library compilation
 * result to fix this.
 * */

module.exports = Module;
