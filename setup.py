"""
Setup script for SOC Analyst AI
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="soc-analyst-ai",
    version="1.0.0",
    author="SOC Team",
    author_email="soc@example.com",
    description="AI-powered Security Operations Center analyst for automated log analysis and reporting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/soc-analyst-ai",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "soc-ai=soc_cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
