<script>
</script>

<svelte:head>
	<title>Welcome</title>
</svelte:head>
<div class="container">
	<div class="row">
		<div class="col-md-2">
			<div class="sidebar d-flex flex-column flex-shrink-0 p-3 text-whiter bg-dark">
				<a
					href="/"
					class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-white text-decoration-none"
				>
					<span class="fs-4">Go Packet Analyser</span>
				</a>
				<hr />
				<ul class="nav nav-pills flex-column mb-auto">
					<li>
						<button
							class="btn btn-toggle align-items-center rounded collapsed text-white"
							data-bs-toggle="collapse"
							data-bs-target="#computer1-collapse"
						>
							Computer 1
						</button>
						<div class="collapse sub-list" id="computer1-collapse">
							<ul class="btn-toggle-nav list-unstyled fw-normal pb-1 small">
								<li>
									<a href="#" class="nav-link text-white"> Interface 1 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 2 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 3 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 4 </a>
								</li>
							</ul>
						</div>
					</li>
					<li>
						<button
							class="btn btn-toggle align-items-center rounded collapsed text-white"
							data-bs-toggle="collapse"
							data-bs-target="#computer2-collapse"
						>
							Computer 2
						</button>
						<div class="collapse sub-list" id="computer2-collapse">
							<ul class="btn-toggle-nav list-unstyled fw-normal pb-1 small">
								<li>
									<a href="#" class="nav-link text-white"> Interface 1 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 2 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 3 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 4 </a>
								</li>
							</ul>
						</div>
					</li>
					<li>
						<button
							class="btn btn-toggle align-items-center rounded collapsed text-white"
							data-bs-toggle="collapse"
							data-bs-target="#computer3-collapse"
						>
							Computer 3
						</button>
						<div class="collapse sub-list" id="computer3-collapse">
							<ul class="btn-toggle-nav list-unstyled fw-normal pb-1 small">
								<li>
									<a href="#" class="nav-link text-white"> Interface 1 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 2 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 3 </a>
								</li>
								<li>
									<a href="#" class="nav-link text-white"> Interface 4 </a>
								</li>
							</ul>
						</div>
					</li>
				</ul>
			</div>
		</div>
		<div class="col-md-10">
			<div class="content d-flex flex-column flex-shrink-0 p-3 text-whiter">
				<input type="text" class="form-control" placeholder="Search Filter">
                <table class="table table-striped table-dark">
                    <thead>
                      <tr>
                        <th scope="col">Src IP</th>
                        <th scope="col">Dst IP</th>
                        <th scope="col">Src Port</th>
                        <th scope="col">Dst Port</th>
                        <th scope="col">Protocol</th>
                        <th scope="col">Src MAC</th>
                        <th scope="col">Dst MAC</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <th scope="row">127.0.0.1</th>
                        <td>127.0.0.2</td>
                        <td>52867</td>
                        <td>443</td>
                        <td>TCP</td>
                        <td>ff:ff:ff:ff:ff:ff</td>
                        <td>ff:ff:ff:ff::ff</td>
                      </tr>
                      <tr>
                        <th scope="row">192.0.0.1</th>
                        <td>192.0.0.2</td>
                        <td>52867</td>
                        <td>52845</td>
                        <td>UDP</td>
                        <td>ff:ff:ff:ff:ff:ff</td>
                        <td>ff:ff:ff:ff::ff</td>
                      </tr>
                      <tr>
                        <th scope="row">127.0.0.1</th>
                        <td>127.0.0.2</td>
                        <td>52867</td>
                        <td>443</td>
                        <td>TCP</td>
                        <td>ff:ff:ff:ff:ff:ff</td>
                        <td>ff:ff:ff:ff::ff</td>
                      </tr>
                    </tbody>
                  </table>
			</div>
		</div>
	</div>
</div>

<style>
	:global(body) {
		height: 100vh;
		background-color: #002b36;
	}
	.btn {
		min-width: 100%;
		text-align: left;
	}
	.btn:focus {
		outline: none;
		box-shadow: none;
	}
	.btn:hover {
		background-color: var(--bs-gray-dark);
	}
	a {
		padding-left: 30px;
	}
	a:hover {
		background-color: var(--bs-gray-dark);
	}
	.sub-list {
		border-left: 1px solid var(--bs-gray);
		margin-left: 30px;
	}
	.container {
		height: 100vh;
		min-width: 100%;
	}
	.row {
		min-height: 100%;
	}
	.col-md-2 {
		padding: 0 4px 0 0;
	}
	.col-md-10 {
		padding: 0;
	}
	.sidebar {
		min-height: 100%;
	}
	.content {
		min-height: 100%;
		background-color: #292129;
	}
</style>
