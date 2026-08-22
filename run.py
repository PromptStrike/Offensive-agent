from oagent.http_target import HTTPLogin
from oagent.tools import Tools
from oagent.brain import LLMBrain
from oagent.controller import Controller

agent = Controller(
    brain=LLMBrain(),
    tools=Tools(HTTPLogin()),
    goal="Find an authentication bypass on the /login endpoint",
)
agent.run()
