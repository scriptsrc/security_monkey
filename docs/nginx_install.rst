============
Nginx setup
============

.. Note::
    You need to have followed the :doc:`easy install <./easy_install>` first.

Nginx is a very popular choice to serve a Python project:

- It's fast.
- It's lightweight.
- Configuration files are simple.

If you have your own server, it's the best choice. If not, try the
 :doc:`easiest setup <./easy_install>`

Nginx doesn't run any Python process, it only serve requests from outside to
the Python server.

Therefor there are two steps:

- Run the Python process.
- Run Nginx.

You will benefit from having:

- the possibility to have several projects listening to the port 80;
- your web site processes won't run with admin rights, even if --user doesn't
  work on your OS;
- the ability to manage a Python process without touching Nginx or the other
  processes. It's very handy for updates.

The Python process
==================

Run Security Monkey as usual, but this time make it listen to a local port and host. E.G::

    python manage.py run_api_server

In PHP, when you edit a file, the changes are immediately visible. In Python,
the whole code is often loaded in memory for performance reasons. This means
you have to restart the Python process to see the changes effect. Having a
separate process let you do this without having to restart the server.

Nginx
======

Nginx can be installed with you usual package manager, so we won't cover
installing it.

You must create a Nginx configuration file for Security Monkey. On GNU/Linux, they usually
go into /etc/nginx/conf.d/. Name it securitymonkey.conf.

The minimal configuration file to run the site is::

    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Strict-Transport-Security "max-age=631138519";
    add_header Content-Security-Policy "default-src 'self'; font-src 'self' https://fonts.gstatic.com; script-src 'self' https://ajax.googleapis.com; style-src 'self' https://fonts.googleapis.com;";

    server {
       listen      0.0.0.0:443 ssl;
       ssl_certificate /etc/ssl/certs/server.crt;
       ssl_certificate_key /etc/ssl/private/server.key;
       access_log  /var/log/security_monkey/security_monkey.access.log;
       error_log   /var/log/security_monkey/security_monkey.error.log;

       location ~* ^/(reset|confirm|healthcheck|register|login|logout|api) {
            proxy_read_timeout 120;
            proxy_pass  http://127.0.0.1:5000;
            proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
            proxy_redirect off;
            proxy_buffering off;
            proxy_set_header        Host            $host;
            proxy_set_header        X-Real-IP       $remote_addr;
            proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /static {
            rewrite ^/static/(.*)$ /$1 break;
            root /usr/local/src/security_monkey/security_monkey/static;
            index ui.html;
        }

        location / {
            root /usr/local/src/security_monkey/security_monkey/static;
            index ui.html;
        }

    }

`proxy_pass` just passes the external request to the Python process.
The port much match the one used by the 0bin process of course.

This makes Nginx serve the favicon and static files which is is much better at than python.
