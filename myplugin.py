from typing import List
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist

class myplugin(plugins.PluginInterface):
    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                           description = 'Memory layer for the kernel',
                           architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols",
                            description = "Windows kernel symbols"),
            requirements.BooleanRequirement(name = 'onlywow64',
                            description = "Only show WoW64 processes",
                            default = False,
                            optional = True)
        ]
    
    def run(self):
        tasks = pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols'])
        wow64 = self.config['onlywow64']
        if wow64:
            tasks = self.onlyWow64(tasks)
        
        return renderers.TreeGrid([("PID", int), ("Image", str), ("WoW64", int)], self._generator(tasks))
    
    def _generator(self, data):
        for task in data:
            yield (0, [
                    int(task.UniqueProcessId),
                    task.ImageFileName.cast("string",
                            max_length = task.ImageFileName.vol.count,
                            errors = 'replace'),
                    int(task.get_is_wow64())
            ])
        
    def onlyWow64(self, tasks):
        for task in tasks:
            if task.get_is_wow64():
                yield task