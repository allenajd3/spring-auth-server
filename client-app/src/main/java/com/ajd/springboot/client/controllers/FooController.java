package com.ajd.springboot.client.controllers;

import java.util.Arrays;
import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import com.ajd.springboot.client.dto.MessageDTO;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController()
@Slf4j
@RequestMapping("/foo")
public class FooController {

	@GetMapping("/call-oauth2")
	public ResponseEntity<String> callOauth2Resource(){
		return ResponseEntity.ok("OK");
	}
	
	@GetMapping("/mensajes")
	public List<MessageDTO> getAllTweets() throws InterruptedException {
	    Thread.sleep(2000L); // delay
	    return Arrays.asList(
	      new MessageDTO("Mensaje1"),
	      new MessageDTO("Mensaje2"),
	      new MessageDTO("Mensaje3"));
	}
	
	
	/**
	 * Ejemplo para ver las diferencias de llamadas entre un RESTTEMPLATE y un WEBCLIENT
	 * 
	 * 
	 */
	@GetMapping("/mensajes-bloqueante")
	public List<MessageDTO> getTweetsBlocking() {
	    log.info("Starting BLOCKING Controller!");
	    final String uri = getSlowServiceUri();

	    RestTemplate restTemplate = new RestTemplate();
	    ResponseEntity<List<MessageDTO>> response = restTemplate.exchange(
	      uri, HttpMethod.GET, null,
	      new ParameterizedTypeReference<List<MessageDTO>>(){});

	    List<MessageDTO> result = response.getBody();
	    result.forEach(tweet -> log.info(tweet.toString()));
	    log.info("Exiting BLOCKING Controller!");
	    return result;
	}
	
	@GetMapping(value = "/mensajes-no-bloqueante", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<MessageDTO> getTweetsNonBlocking() {
        log.info("Starting NON-BLOCKING Controller!");
        Flux<MessageDTO> tweetFlux = WebClient.create()
          .get()
          .uri(getSlowServiceUri())
          .retrieve()
          .bodyToFlux(MessageDTO.class);

        tweetFlux.buffer(tweet -> log.info(tweet.toString()));
        log.info("Exiting NON-BLOCKING Controller!");
        return tweetFlux;
    }
	
    private String getSlowServiceUri() {
        return "http://127.0.0.1:8080/foo/mensajes";
    }
}
