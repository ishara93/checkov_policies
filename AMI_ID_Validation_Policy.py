from lark import Token

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import logging
import json

class CKV_AWS_999(BaseResourceCheck):
    def __init__(self):
        self.logger = logging.getLogger("{}".format(self.__module__))
        name = "Ensure That AMI ID is ami-830c94e3"
        id = "CKV_AWS_999"
        supported_resources = '*'
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        self.logger.debug("ssss" + json.dumps(conf))
        if 'tags' in conf.keys():
            if conf['tags'][0]['env'] == "prod":
                return CheckResult.PASSED     
        return CheckResult.FAILED


scanner = CKV_AWS_999()
