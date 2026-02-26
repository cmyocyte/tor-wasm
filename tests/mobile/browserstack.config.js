/**
 * BrowserStack configuration for mobile browser testing.
 *
 * Tests that tor-wasm works across mobile browsers that users in
 * censored countries actually use:
 *   - iOS Safari (Iran, general)
 *   - Android Chrome (everywhere)
 *   - Samsung Internet (popular in some markets)
 *   - Yandex Browser (Russia)
 *
 * Run: npx browserstack-runner --config tests/mobile/browserstack.config.js
 * Requires BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY env vars.
 */

module.exports = {
    // BrowserStack credentials (from env)
    username: process.env.BROWSERSTACK_USERNAME,
    key: process.env.BROWSERSTACK_ACCESS_KEY,

    // Test framework
    framework: 'custom',
    test_path: ['tests/mobile/core-suite.js'],

    // Project info
    project: 'tor-wasm',
    build: `mobile-${new Date().toISOString().slice(0, 10)}`,

    // Test timeout (circuit build can be slow on mobile)
    timeout: 120, // seconds

    // Device matrix
    browsers: [
        // iOS Safari — most important for iPhone-heavy markets (Iran)
        {
            browser: 'safari',
            os: 'ios',
            os_version: '17',
            device: 'iPhone 15',
            real_mobile: true,
            name: 'iOS Safari 17 (iPhone 15)',
        },
        // iOS Chrome — some users prefer Chrome on iOS
        {
            browser: 'chrome',
            os: 'ios',
            os_version: '17',
            device: 'iPhone 15',
            real_mobile: true,
            name: 'iOS Chrome (iPhone 15)',
        },
        // Android Chrome — most common mobile browser globally
        {
            browser: 'chrome',
            os: 'android',
            os_version: '14.0',
            device: 'Google Pixel 8',
            real_mobile: true,
            name: 'Android Chrome 120 (Pixel 8)',
        },
        // Android Firefox — privacy-focused users
        {
            browser: 'firefox',
            os: 'android',
            os_version: '14.0',
            device: 'Google Pixel 8',
            real_mobile: true,
            name: 'Android Firefox (Pixel 8)',
        },
        // Samsung Internet — significant market share in Asia
        {
            browser: 'samsung',
            os: 'android',
            os_version: '14.0',
            device: 'Samsung Galaxy S24',
            real_mobile: true,
            name: 'Samsung Internet (Galaxy S24)',
        },
    ],

    // Capabilities
    capabilities: {
        'browserstack.debug': true,
        'browserstack.console': 'info',
        'browserstack.networkLogs': true,
        'browserstack.local': false,
    },
};
