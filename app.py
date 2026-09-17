import hmac
import os
import re
import secrets
import stat
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash


def human(size):
    value = float(size)
    for unit in ('б', 'кб', 'мб', 'гб', 'тб'):
        if value < 1024 or unit == 'тб':
            return f'{value:.1f} {unit}'
        value /= 1024


def fmt(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%d %b · %H:%M')


def create_app():
    secret = os.environ.get('DROP_SECRET_KEY', '')
    user = os.environ.get('DROP_USER', '').strip()
    password_hash = os.environ.get('DROP_PASSWORD_HASH', '')
    if len(secret) < 32 or not user or not re.fullmatch(
        r'(?:scrypt:[0-9]+:[0-9]+:[0-9]+|pbkdf2:sha256:[0-9]+)\$[A-Za-z0-9]+\$[0-9a-f]+', password_hash
    ):
        raise ValueError('задай секрет от 32 символов, логин и werkzeug-хеш пароля')
    max_mb = int(os.environ.get('DROP_MAX_MB') or '100')
    if max_mb < 1:
        raise ValueError('лимит загрузки должен быть положительным')
    secure = os.environ.get('DROP_COOKIE_SECURE') or '1'
    if secure not in ('0', '1'):
        raise ValueError('DROP_COOKIE_SECURE должен быть 0 или 1')
    root = Path(os.environ.get('DROP_DATA_DIR') or 'data').absolute()
    for path in (root, root / 'files', root / 'notes', root / 'keys'):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError('каталог данных не должен содержать симлинки')
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret,
        DROP_USER=user,
        DROP_PASSWORD_HASH=password_hash,
        DROP_DATA_DIR=root,
        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=1024 * 1024,
        MAX_FORM_PARTS=20,
        SESSION_COOKIE_SECURE=secure == '1',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )
    def csrf_token():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(32)
        return session['csrf']

    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def protect():
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
            expected = session.get('csrf', '')
            if not expected or not hmac.compare_digest(token.encode(), expected.encode()):
                abort(400, 'неверный csrf-токен')
        if request.endpoint and request.endpoint not in ('login', 'static', 'dlpub'):
            if not session.get('ok'):
                if request.method != 'GET':
                    abort(401)
                return redirect(url_for('login'))

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            valid = check_password_hash(password_hash, request.form.get('p', ''))
            if valid and hmac.compare_digest(request.form.get('u', '').encode(), user.encode()):
                session.clear()
                session['ok'] = True
                session.permanent = request.form.get('rm') == 'on'
                csrf_token()
                return redirect(url_for('index'))
            return render_template('login.html', error=True), 401
        if session.get('ok'):
            return redirect(url_for('index'))
        return render_template('login.html', error=False)

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    def checked_path(folder, name):
        if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,139}', name):
            abort(404)
        p = root / folder / name
        if any(parent.is_symlink() for parent in (p, *p.parents)):
            abort(404)
        return p

    def open_directory(path):
        # каждый компонент открывается без переходов по симлинкам
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = next_fd
            return directory
        except OSError:
            os.close(directory)
            abort(404)

    def open_regular(p, flags=os.O_RDONLY):
        directory = open_directory(p.parent)
        fd = None
        try:
            fd = os.open(p.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                abort(404)
            stream = os.fdopen(fd, 'rb' if flags == os.O_RDONLY else 'r+b')
            fd = None
            return stream
        except OSError:
            abort(404)
        finally:
            os.close(directory)
            if fd is not None:
                os.close(fd)

    def safe_file(name):
        p = checked_path('files', name)
        with open_regular(p):
            pass
        return p

    def note_path(slug):
        if not re.fullmatch(r'[a-z0-9_-]{1,80}', slug):
            abort(404)
        return checked_path('notes', slug + '.txt')

    def download(p):
        stream = open_regular(p)
        try:
            response = send_file(stream, as_attachment=True, download_name=p.name)
            response.content_length = os.fstat(stream.fileno()).st_size
            response.call_on_close(stream.close)
            return response
        except BaseException:
            stream.close()
            raise

    def read_text(p):
        with open_regular(p) as stream:
            return stream.read().decode('utf-8', errors='replace')

    def create_unique(folder, name, start=1):
        stem, suffix = Path(name).stem, Path(name).suffix
        n = start
        candidate = name
        directory = open_directory(root / folder)
        try:
            while True:
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    return root / folder / candidate, os.fdopen(fd, 'wb')
                except FileExistsError:
                    candidate = f'{stem}-{n}{suffix}'
                    n += 1
        finally:
            os.close(directory)

    @app.get('/')
    def index():
        files = []
        for p in sorted((root / 'files').iterdir(), reverse=True):
            if p.is_file() and not p.is_symlink():
                st = p.stat()
                files.append(dict(name=p.name, size=st.st_size, hs=human(st.st_size), mt=fmt(st.st_mtime)))
        notes = []
        for p in sorted((root / 'notes').glob('*.txt'), reverse=True):
            if p.is_file() and not p.is_symlink():
                st = p.stat()
                text = read_text(checked_path('notes', p.name))
                notes.append(dict(slug=p.stem, title=text.split('\n')[0][:200] or '(пусто)', chars=st.st_size, mt=fmt(st.st_mtime), lines=text.count('\n')))
        return render_template('index.html', files=files, notes=notes, user=user)

    @app.post('/upload')
    def upload():
        f = request.files.get('file')
        if not f or not f.filename:
            return redirect(url_for('index', e='file'))
        raw = os.path.basename(f.filename.replace('\\', '/'))
        name = re.sub(r'[^A-Za-z0-9_.-]', '_', raw).strip('._')[:120]
        if not name:
            return redirect(url_for('index', e='name'))
        target, stream = create_unique('files', name)
        try:
            with stream as out:
                while chunk := f.stream.read(1 << 20):
                    out.write(chunk)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return redirect(url_for('index', ok='up'))

    @app.get('/f/<name>')
    def down(name):
        p = safe_file(name)
        return download(p)

    @app.post('/f/<name>/share')
    def share(name):
        p = safe_file(name)
        for key in (root / 'keys').iterdir():
            if key.is_file() and not key.is_symlink() and read_text(checked_path('keys', key.name)) == p.name:
                return {'url': f'/dl/{key.name}'}
        token = secrets.token_hex(16)
        directory = open_directory(root / 'keys')
        try:
            fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'w') as out:
                out.write(p.name)
        finally:
            os.close(directory)
        return {'url': f'/dl/{token}'}

    @app.get('/dl/<token>')
    def dlpub(token):
        if not re.fullmatch(r'[0-9a-f]{32}', token):
            abort(404)
        key = checked_path('keys', token)
        name = read_text(key)
        p = safe_file(name)
        return download(p)

    @app.post('/f/<name>/del')
    def fdel(name):
        p = safe_file(name)
        p.unlink(missing_ok=True)
        for key in (root / 'keys').iterdir():
            try:
                if not key.is_symlink() and read_text(checked_path('keys', key.name)) == p.name:
                    key.unlink()
            except OSError:
                pass
        return redirect(url_for('index', ok='del'))

    @app.post('/note/new')
    def nnew():
        text = (request.form.get('name') or secrets.token_hex(3)).strip().lower()
        slug = re.sub(r'[^a-z0-9_-]', '', text)[:60]
        target, stream = create_unique('notes', f'{slug or "note"}.txt', start=2)
        stream.close()
        return redirect(url_for('nedit', slug=target.stem))

    @app.get('/note/<slug>')
    def nedit(slug):
        p = note_path(slug)
        return render_template('edit.html', slug=slug, content=read_text(p))

    @app.post('/note/<slug>/save')
    def nsave(slug):
        p = note_path(slug)
        text = request.form.get('c', '').encode('utf-8')
        with open_regular(p, os.O_RDWR) as stream:
            stream.write(text)
            stream.truncate()
        return redirect(url_for('nedit', slug=slug))

    @app.post('/note/<slug>/del')
    def ndel(slug):
        p = note_path(slug)
        with open_regular(p):
            pass
        p.unlink(missing_ok=True)
        return redirect(url_for('index', ok='del'))

    return app
