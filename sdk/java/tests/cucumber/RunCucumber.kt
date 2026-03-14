package cucumber

import io.cucumber.junit.Cucumber
import io.cucumber.junit.CucumberOptions
import org.junit.runner.RunWith

@RunWith(Cucumber::class)
@CucumberOptions(
    features = ["../tests/client_sanity/features"],
    glue = ["cucumber"],
    tags = "not @skip_kotlin",
    plugin = [
        "pretty",
        "json:../tests/client_sanity/artifacts/cucumber_kotlin.json"
    ]
)
class RunCucumber
