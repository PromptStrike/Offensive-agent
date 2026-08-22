from oagent.target import BlindLogin
from oagent.tools import Tools
from oagent.brain import LLMBrain
from oagent.controller import Controller

agent = Controller(
    brain=LLMBrain(),
    tools=Tools(BlindLogin()),
    goal="Find an authentication bypass on the /login endpoint",
)
agent.run()
