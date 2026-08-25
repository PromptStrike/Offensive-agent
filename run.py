from oagent.http_target import HTTPTarget
from oagent.tools import Tools
from oagent.brain import LLMBrain
from oagent.controller import Controller

agent = Controller(
    brain=LLMBrain(),
    tools=Tools(HTTPTarget()),
    goal="Find a broken access control / unauthorized data access vulnerability on the /profile endpoint",
)
agent.run()
