import importlib.util
import io
import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash


class ConfigTests(unittest.TestCase):
    def test_required_environment(self):
        self.assertIsNotNone(importlib.util.find_spec('app'), 'нет фабрики приложения')
        from app import create_app
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                create_app()

    def test_secure_defaults(self):
        from app import create_app
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as root:
            with patch.dict(os.environ, {
                'DROP_SECRET_KEY': 'a' * 64,
                'DROP_USER': 'tester',
                'DROP_PASSWORD_HASH': generate_password_hash('test-only-pass'),
                'DROP_DATA_DIR': root,
            }, clear=True):
                app = create_app()
                self.assertTrue(app.config['SESSION_COOKIE_SECURE'])
                self.assertTrue(app.config['SESSION_COOKIE_HTTPONLY'])
                self.assertEqual(app.config['SESSION_COOKIE_SAMESITE'], 'Lax')
                self.assertEqual(app.config['MAX_CONTENT_LENGTH'], 100 * 1024 * 1024)
                self.assertFalse(app.debug)


class AppTests(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        with patch.dict(os.environ, {
            'DROP_SECRET_KEY': 'a' * 64,
            'DROP_USER': 'tester',
            'DROP_PASSWORD_HASH': generate_password_hash('test-only-pass'),
            'DROP_DATA_DIR': str(self.root),
            'DROP_COOKIE_SECURE': '0',
            'DROP_MAX_MB': '1',
        }, clear=True):
            self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def csrf(self, client=None):
        client = client or self.client
        with client.session_transaction() as session:
            return session['csrf']

    def login(self, client=None):
        client = client or self.client
        self.assertEqual(client.get('/login').status_code, 200)
        return client.post('/login', data={
            'u': 'tester', 'p': 'test-only-pass', 'csrf_token': self.csrf(client),
        })

    def post(self, url, **kwargs):
        return self.client.post(url, headers={'X-CSRF-Token': self.csrf()}, **kwargs)

    def test_upload_download_exclusive(self):
        self.login()
        for content in (b'first', b'second'):
            self.assertEqual(self.post('/upload', data={'file': (io.BytesIO(content), 'report.txt')}).status_code, 302)
        self.assertEqual((self.root / 'files/report.txt').read_bytes(), b'first')
        self.assertEqual((self.root / 'files/report-1.txt').read_bytes(), b'second')
        with self.client.get('/f/report.txt') as response:
            self.assertEqual(response.data, b'first')
            self.assertIn('attachment', response.headers['Content-Disposition'])
            self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertIn(b'report-1.txt', self.client.get('/').data)

    def test_persistent_share_post_only_and_delete(self):
        self.login()
        self.post('/upload', data={'file': (io.BytesIO(b'<script>test</script>'), 'page.html')})
        self.assertEqual(self.client.get('/f/page.html/share').status_code, 405)
        self.assertEqual(self.client.post('/f/page.html/share').status_code, 400)
        response = self.post('/f/page.html/share')
        self.assertEqual(response.status_code, 200)
        url = response.json['url']
        self.assertEqual(self.post('/f/page.html/share').json['url'], url)
        public = self.app.test_client()
        for _ in range(2):
            with public.get(url) as download:
                self.assertEqual(download.status_code, 200)
                self.assertEqual(download.data, b'<script>test</script>')
                self.assertIn('attachment', download.headers['Content-Disposition'])
        self.assertEqual(self.post('/f/page.html/del').status_code, 302)
        self.assertEqual(public.get(url).status_code, 404)
        self.post('/upload', data={'file': (io.BytesIO(b'new'), 'page.html')})
        self.assertEqual(public.get(url).status_code, 404)

    def test_symlinks_and_path_validation(self):
        self.login()
        outside = self.root / 'outside.txt'
        outside.write_text('private')
        (self.root / 'files/link.txt').symlink_to(outside)
        (self.root / 'notes/link.txt').symlink_to(outside)
        token = 'b' * 32
        (self.root / 'keys' / token).write_text('link.txt')
        for url in ('/f/link.txt', '/note/link', '/dl/' + token, '/f/../outside.txt', '/f/%2e%2e%2foutside.txt'):
            with self.client.get(url) as response:
                self.assertEqual(response.status_code, 404, url)
        for url in ('/note/link/save', '/note/link/del', '/f/link.txt/share', '/f/link.txt/del'):
            self.assertEqual(self.post(url, data={'c': 'changed'}).status_code, 404, url)
        self.assertEqual(outside.read_text(), 'private')
        (self.root / 'notes/plain.txt').write_text('original')
        self.assertEqual(self.post('/note/p!lain/save', data={'c': 'changed'}).status_code, 404)
        self.assertEqual((self.root / 'notes/plain.txt').read_text(), 'original')
        (self.root / 'keys' / token).unlink()
        (self.root / 'keys' / token).symlink_to(outside)
        self.assertEqual(self.client.get('/dl/' + token).status_code, 404)

    def test_replaced_storage_directory_is_rejected(self):
        self.login()
        files = self.root / 'files'
        files.rmdir()
        external = self.root / 'external'
        external.mkdir()
        files.symlink_to(external, target_is_directory=True)
        self.assertEqual(self.post('/upload', data={'file': (io.BytesIO(b'x'), 'x.txt')}).status_code, 404)
        self.assertEqual(list(external.iterdir()), [])

    def test_frontend_mutations_use_csrf(self):
        js = (Path(__file__).resolve().parents[1] / 'static/files.js').read_text()
        self.assertIn("'X-CSRF-Token'", js)
        self.assertIn("route(x,'/share'),{method:'POST'}", js)
        self.assertIn("hidden.name='csrf_token'", js)

    def test_notes_crud_and_csrf(self):
        self.login()
        response = self.post('/note/new', data={'name': 'sample'})
        self.assertEqual(response.status_code, 302)
        url = response.location
        self.assertEqual(self.post('/note/new', data={'name': 'sample'}).location, '/note/sample-2')
        self.assertEqual(self.post(url + '/save', data={'c': '<script>text</script>\nhello'}).status_code, 302)
        page = self.client.get(url)
        self.assertIn(b'&lt;script&gt;text&lt;/script&gt;', page.data)
        self.assertIn(b'hello', page.data)
        for path in ('/upload', '/note/new', url + '/save', url + '/del', '/logout', '/f/x/share', '/f/x/del'):
            self.assertEqual(self.client.post(path).status_code, 400, path)
        self.assertEqual(self.post(url + '/del').status_code, 302)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.post(url + '/save', data={'c': 'gone'}).status_code, 404)

    def test_upload_limit_and_auth(self):
        self.client.get('/login')
        self.assertEqual(self.post('/upload').status_code, 401)
        self.login()
        with self.post('/upload', data={'file': (io.BytesIO(b'x' * (1024 * 1024 + 1)), 'big.bin')}) as response:
            self.assertEqual(response.status_code, 413)
            response.request.environ['wsgi.input'].close()
        self.assertEqual(list((self.root / 'files').iterdir()), [])
        self.assertIn('e=file', self.post('/upload').location)
        self.assertIn('e=name', self.post('/upload', data={'file': (io.BytesIO(b'x'), '..')}).location)

    def test_parallel_uploads_do_not_overwrite(self):
        def upload(number):
            client = self.app.test_client()
            with client.session_transaction() as state:
                state.update(ok=True, csrf='test-token')
            return client.post('/upload', headers={'X-CSRF-Token': 'test-token'}, data={'file': (io.BytesIO(str(number).encode()), 'same.txt')}).status_code
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(upload, range(24))), [302] * 24)
        paths = list((self.root / 'files').iterdir())
        self.assertEqual(len(paths), 24)
        self.assertTrue(all(p.suffix == '.txt' for p in paths))
        self.assertEqual({p.read_text() for p in paths}, {str(n) for n in range(24)})

    def test_login_logout_csrf(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        page = self.client.get('/login')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'name="csrf_token"', page.data)
        old_csrf = self.csrf()
        self.assertEqual(self.client.post('/login', data={'u': 'tester', 'p': 'test-only-pass'}).status_code, 400)
        bad = self.client.post('/login', data={'u': 'tester', 'p': 'wrong', 'csrf_token': old_csrf})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        self.assertNotEqual(old_csrf, self.csrf())
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.assertEqual(self.client.post('/logout').status_code, 400)
        self.assertEqual(self.post('/logout').status_code, 302)
        self.assertEqual(self.client.get('/').status_code, 302)


if __name__ == '__main__':
    unittest.main()
