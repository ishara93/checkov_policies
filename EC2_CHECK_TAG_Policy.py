from lark import Token

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import logging
import json

class CKV_AWS_999(BaseResourceCheck):
    def __init__(self):
        self.logger = logging.getLogger("{}".format(self.__module__))
        name = "Ensure That Ec2 has atleast one or more tags"
        id = "CKV_AWS_999"
        supported_resources = '*'
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        self.logger.debug("ssss" + json.dumps(conf))
        if 'tags' in conf.keys():
            if len(conf['tags']) > 0:
                return CheckResult.PASSED     
        return CheckResult.FAILED


scanner = CKV_AWS_999()
