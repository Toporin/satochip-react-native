
const IS_DEV = typeof __DEV__ !== 'undefined' ? __DEV__ : process.env.NODE_ENV === 'development';

export function console_log(...args: any[]) {
  if (IS_DEV) {
    console.log('[Satochip]', ...args);
  }
}