from flask import Blueprint
from autodoc import Autodoc

from const import API_PREFIX

document = Blueprint('document', __name__)
autodoc = Autodoc()


@document.route(API_PREFIX + '/documents')
def document_get():
    return autodoc.html(groups=['public'],
                        title="LiveCloud API Documentation")


@document.route(API_PREFIX + '/documents/networks')
def network_document_get():
    return autodoc.html(groups=['network_app'],
                        title="LiveCloud API Documentation")


@document.route(API_PREFIX + '/documents/subnets')
def subnet_document_get():
    return autodoc.html(groups=['subnet_app'],
                        title="LiveCloud API Documentation")


@document.route(API_PREFIX + '/documents/ports')
def port_document_get():
    return autodoc.html(groups=['port_app'],
                        title="LiveCloud API Documentation")
