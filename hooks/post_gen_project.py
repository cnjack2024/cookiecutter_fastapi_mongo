import hashlib
import os
import ulid

from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def template_render(filename):
    file = Path(filename)

    if file.is_file():
        loader = FileSystemLoader(os.getcwd())
        env = Environment(
            loader=loader, variable_start_string="<<", variable_end_string=">>"
        )

        context = {
            "aes_key": ulid.ulid()[:16],
            "aes_iv": ulid.ulid()[:16],
            "secret_key": hashlib.sha256(ulid.ulid().encode()).hexdigest(),
        }

        template = env.get_template(file.as_posix())
        content = template.render(context)

        with open(file.as_posix(), "w", encoding="utf-8") as f:
            f.write(content + "\n")


def install_venv():
    os.system("python3 -m venv venv")
    os.system(
        "source venv/bin/activate && pip install -U pip && pip install -r requirements.txt && python cmd/generate/main.py init_app admin AdminUser"
    )


if __name__ == "__main__":
    template_render("config.py")

    if {{cookiecutter.venv}}:
        install_venv()
